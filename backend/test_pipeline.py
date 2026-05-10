import asyncio, sys
sys.path.insert(0, ".")
from pipeline import run_pipeline_from_json

async def main():
    result = await run_pipeline_from_json({
        "prompt": "fix SQL injection in users/views.py",
        "mode": "secure",
        "repo": "test/repo"
    })
    print("decision:", result.get("decision"))
    print("iterations:", result.get("repair", {}).get("iterations"))

asyncio.run(main())
