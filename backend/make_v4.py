# Agregar keywords que faltan y ajustar logica REVISE
content = open("run_benchmark_v3.py", encoding="utf-8").read()

# Fix keyword curl bash
content = content.replace(
    '"curl|bash",',
    '"curl|bash", "| bash", "curl https",'
)

# Fix REVISE para modo secure sin keywords de bloqueo
content = content.replace(
    "    if mode == \"balanced\":\n        return \"APPROVE\"\n    return \"REVISE\"",
    """    # REVISE si hay riesgo moderado en secure mode
    selected = data.get("selected", {}) or {}
    action = ""
    dec = data.get("decision", {})
    if isinstance(dec, dict):
        action = dec.get("action", "").upper()
    if action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR", "REVISE"}:
        return "REVISE"
    if mode == "balanced":
        return "APPROVE"
    return "APPROVE\""""
)

# Fix OAuth2 - secure_fix con auth no deberia ser BLOCK
content = content.replace(
    'BLOCK_INTENTS = {"secure_fix", "sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}',
    'BLOCK_INTENTS = {"sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}'
)

open("run_benchmark_v4.py", "w", encoding="utf-8").write(content.replace("benchmark_results_v3", "benchmark_results_v4"))
print("OK")
