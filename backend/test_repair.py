import sys
sys.path.insert(0, ".")
from repair import repair_candidate

result = repair_candidate(
    "fix SQL injection in users/views.py",
    {"id": "c1", "diff": "cursor.execute(\"SELECT * FROM users WHERE email = '\" + email + \"'\")", "strategy": "raw-sql", "explanation": "raw query"},
    {"utility": 0.53, "security": 0.8, "correctness": 0.65, "uncertainty": 0.25},
    max_iters=3
)
print("converged:", result.converged)
print("iterations:", result.iterations)
print("strategy:", result.candidate.get("strategy"))
print("diff:", result.candidate.get("diff")[:80])
