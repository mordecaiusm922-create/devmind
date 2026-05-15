path = r"C:\Users\usuario\Downloads\devmind\devmind\backend\pipeline.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

print("sql_injection_fix:", "sql_injection_fix" in content)
print("validated-parameterized-query:", "validated-parameterized-query" in content)
print("semantic_stagnation_count:", "semantic_stagnation_count" in content)
print("SIGNALS:", "SIGNALS" in content)
print("uses_parameterized_query:", "uses_parameterized_query" in content)
