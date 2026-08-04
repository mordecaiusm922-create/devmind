import json, urllib.request

body = json.dumps({
    "prompt": "fix sql injection in login.py",
    "mode": "secure",
    "files": [{"filename": "login.py", "content": "query = f\"SELECT * FROM users WHERE user='{user}'\""}]
}).encode()

req = urllib.request.Request(
    "https://devmind-2cej.onrender.com/safety-flow",
    data=body,
    headers={"Content-Type": "application/json", "X-Api-Key": "dm-5db56ee14229-4daa8e87edef25a4b17c"}
)
with urllib.request.urlopen(req, timeout=30) as r:
    data = json.loads(r.read())

print("decision:", data.get("decision"))
print("action:", data.get("action"))
print("selected keys:", list(data.get("selected", {}).keys()) if data.get("selected") else None)
print("risk_adjusted_utility:", data.get("selected", {}).get("risk_adjusted_utility") if data.get("selected") else None)
print()
print(json.dumps(data, indent=2)[2000:3500])
