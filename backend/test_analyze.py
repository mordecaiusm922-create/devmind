import sys, asyncio
sys.path.insert(0, ".")
import os
os.environ.setdefault("GROQ_API_KEY", "test")

from main import _pipeline_sync
try:
    result = _pipeline_sync("django/django", 17379, "test-trace")
    print("score:", result.get("risk", {}).get("score"))
    print("band:", result.get("risk", {}).get("band"))
    print("surface:", result.get("risk", {}).get("surface"))
except Exception as e:
    print("ERROR:", e)
