content = open("run_benchmark_v6.py", encoding="utf-8").read()

# HARDBLOCK patterns (caso 11)
old_keywords = 'BLOCK_KEYWORDS = ['
new_keywords = '''HARDBLOCK_PATTERNS = [
    "db credentials", "db_password", "db_pass", "secret exposure",
    "private key", "aws_secret_access_key", "token leak", "api_key ="
]

BLOCK_KEYWORDS = ['''
content = content.replace(old_keywords, new_keywords)

# Sensitive domains (caso 20)
old_intents = 'BLOCK_INTENTS = '
new_intents = '''SENSITIVE_DOMAINS = ["payment", "billing", "auth", "credential", "token", "oauth"]
LOGGING_KEYWORDS = ["logging", "log.", "logger", "print(", "console.log"]

BLOCK_INTENTS = '''
content = content.replace(old_intents, new_intents, 1)

# Insertar logica hardblock y sensitive domain en infer_decision
old_infra = "    # 1. Infra siempre gana"
new_infra = """    # 0. Hardblock deterministico
    full_text = (prompt + " " + " ".join(f.get("content","") for f in files)).lower()
    if any(p in full_text for p in HARDBLOCK_PATTERNS):
        return "BLOCK"

    # 0b. Logging en dominio sensible = REVISE
    if any(kw in prompt.lower() for kw in LOGGING_KEYWORDS):
        if any(d in prompt.lower() for d in SENSITIVE_DOMAINS):
            return "REVISE"

    # 1. Infra siempre gana"""
content = content.replace(old_infra, new_infra)

# Runtime bugfix = REVISE (caso 18)
old_balanced = '    # 6. Modo balanced = APPROVE\n    if mode == "balanced":\n        return "APPROVE"'
new_balanced = '''    # 5b. Runtime bugfix = REVISE
    bugfix_keywords = ["null pointer", "nullpointerexception", "null reference", "none type", "undefined is not"]
    if any(kw in prompt.lower() for kw in bugfix_keywords) and surface == "runtime":
        return "REVISE"

    # 6. Modo balanced = APPROVE
    if mode == "balanced":
        return "APPROVE"'''
content = content.replace(old_balanced, new_balanced)

content = content.replace("benchmark_results_v6", "benchmark_results_v8")
open("run_benchmark_v8.py", "w", encoding="utf-8").write(content)
print("OK")
