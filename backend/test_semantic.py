import sys, os
sys.path.insert(0, ".")

# Carga la API key directamente sin dotenv
import dotenv
# Busca el .env en el directorio padre
env_path = r"C:\Users\usuario\Downloads\devmind\devmind\.env"
if not os.path.exists(env_path):
    env_path = r"C:\Users\usuario\Downloads\devmind\.env"

# Lee manualmente para evitar el error de encoding
try:
    with open(env_path, "r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os.environ[k.strip()] = v.strip().strip('"')
except Exception as e:
    print("env error:", e)

print("GROQ_API_KEY set:", bool(os.environ.get("GROQ_API_KEY")))

from semantic_engine import analyze_diff

diff = 'cursor.execute("SELECT * FROM users WHERE email = %s", [email])'
result = analyze_diff(diff, intent="sql_injection_fix")
import json
print(json.dumps(result, indent=2))
