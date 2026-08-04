import sys
sys.path.insert(0, ".")
from runtime.sandbox import sandbox_candidate

code = 'cursor.execute("SELECT * FROM users WHERE email = %s", [email])'
result = sandbox_candidate(code)
print("syntax_valid:", result["syntax_valid"])
print("ast_safe:", result["ast_safe"])
print("bandit_issues:", result["bandit_issues"])
print("evidence_type:", result["evidence_type"])
