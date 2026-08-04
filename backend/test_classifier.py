import sys
sys.path.insert(0, ".")
from surface_classifier import classify_change_surface

# Caso 1: docs change (el PR de Django que alucinó)
ctx = classify_change_surface(
    [{"filename": "docs/topics/testing/overview.txt"}],
    diff="MD5PasswordHasher -> ScryptPasswordHasher"
)
print("=== DOCS CHANGE ===")
print("surface:", ctx.surface)
print("risk_multiplier:", ctx.risk_multiplier)
print("disable_fix_generation:", ctx.disable_fix_generation)
print("disable_runtime_security:", ctx.disable_runtime_security)
print("use_lightweight_pipeline:", ctx.use_lightweight_pipeline)
print("negative_signals:", ctx.negative_signals)

print()

# Caso 2: runtime code change
ctx2 = classify_change_surface(
    [{"filename": "backend/views.py"}],
    diff='cursor.execute("SELECT * FROM users WHERE email = '" + email + "'")'
)
print("=== RUNTIME CODE ===")
print("surface:", ctx2.surface)
print("risk_multiplier:", ctx2.risk_multiplier)
print("disable_fix_generation:", ctx2.disable_fix_generation)
print("disable_runtime_security:", ctx2.disable_runtime_security)
