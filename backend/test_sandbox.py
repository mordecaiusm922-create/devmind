import sys
sys.path.insert(0, ".")
from sandbox import run_sandbox

result = run_sandbox(
    'cursor.execute("SELECT * FROM users WHERE email = %s", [email])',
    timeout_seconds=5
)
print("syntax_valid:", result["syntax_valid"])
print("static_issues:", result["static_issues"])
print("evidence_type:", result["evidence_type"])
print("status:", result["status"])
