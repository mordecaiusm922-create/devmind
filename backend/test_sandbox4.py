import sys
sys.path.insert(0, ".")
from runtime.sandbox import sandbox_candidate

code = 'cursor.execute("SELECT * FROM users WHERE email = %s", [email])'
result = sandbox_candidate(code)
for k, v in result.items():
    print(f"{k}: {v}")
