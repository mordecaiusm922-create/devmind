import sys, os
sys.path.insert(0, ".")

# Simula el surface classifier
from surface_classifier import classify_change_surface

files = [{"filename": "docs/topics/testing/overview.txt", "patch": "MD5 -> Scrypt"}]
ctx = classify_change_surface(files, "MD5 -> Scrypt")
print("surface:", ctx.surface)
print("risk_multiplier:", ctx.risk_multiplier)
print("OK")
