"""
benchmark/run_benchmark.py
Analiza PRs reales y guarda resultados en CSV para construir el dataset de DevMind.
"""
import csv
import json
import time
import requests

API_URL = "https://devmind-2cej.onrender.com"
API_KEY = "devmind-key-123"

# 500 PRs reales de repos públicos — empezamos con 20 para validar
PRS = [
    {"repo": "psf/requests",    "pr": 6710,  "expected_risk": "medium",   "notes": "CVE-2024-35195, TLS change"},
    {"repo": "django/django",   "pr": 17473, "expected_risk": "critical",  "notes": "SECRET_KEY hardcoded"},
    {"repo": "psf/black",       "pr": 3864,  "expected_risk": "low",       "notes": "mypy version bump"},
    {"repo": "encode/httpx",    "pr": 3109,  "expected_risk": "low",       "notes": "dependency update"},
    {"repo": "tiangolo/fastapi","pr": 11804, "expected_risk": "low",       "notes": "docs update"},
    {"repo": "redis/redis-py",  "pr": 2900,  "expected_risk": "medium",    "notes": "auth change"},
    {"repo": "pallets/flask",   "pr": 5992,  "expected_risk": "high",      "notes": "13 CVEs fixed"},
    {"repo": "pallets/flask",   "pr": 5987,  "expected_risk": "high",      "notes": "CVE-2024-34069 werkzeug"},
    {"repo": "pallets/flask",   "pr": 5989,  "expected_risk": "low",       "notes": "docs typo fix"},
    {"repo": "pallets/flask",   "pr": 5984,  "expected_risk": "critical",  "notes": "planted bugs and vulnerabilities"},
]

def analyze_pr(repo, pr_number):
    try:
        response = requests.post(
            f"{API_URL}/analyze-pr",
            headers={"Content-Type": "application/json", "X-Api-Key": API_KEY},
            json={"repo": repo, "pr_number": pr_number},
            timeout=120
        )
        if response.status_code == 200:
            return response.json()
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None
    print(f"  HTTP {response.status_code}: {response.text[:200]}")
    return None

def run():
    results = []
    for item in PRS:
        print(f"Analyzing {item['repo']}#{item['pr']}...")
        data = analyze_pr(item["repo"], item["pr"])
        if data:
            actual_risk = data.get("summary", {}).get("risk", {}).get("level", "unknown")
            correct = actual_risk == item["expected_risk"]
            results.append({
                "repo": item["repo"],
                "pr": item["pr"],
                "expected_risk": item["expected_risk"],
                "actual_risk": actual_risk,
                "correct": correct,
                "confidence": data.get("evaluation", {}).get("confidence_score", 0),
                "security_tags": ",".join(data.get("pre_analysis", {}).get("risk_tags", [])),
                "notes": item["notes"],
            })
            status = "✅" if correct else "❌"
            print(f"  {status} Expected: {item['expected_risk']} | Got: {actual_risk}")
        else:
            print(f"  ⚠️ Failed to analyze")
        time.sleep(3)

    # Guardar CSV
    with open("benchmark/results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)

    # Resumen
    correct = sum(1 for r in results if r["correct"])
    print(f"\n{'='*50}")
    print(f"Accuracy: {correct}/{len(results)} = {correct/len(results)*100:.1f}%")
    print(f"Results saved to benchmark/results.csv")

if __name__ == "__main__":
    run()