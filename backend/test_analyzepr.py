import json, urllib.request

body = json.dumps({
    "prompt": "fix sql injection in login.py",
    "mode": "secure",
    "files": [{"filename": "login.py", "content": "query = f\"SELECT * FROM users WHERE user='{user}'\""}]
}).encode()

req = urllib.request.Request(
    "https://devmind-2cej.onrender.com/analyze-pr",
    data=body,
    headers={"Content-Type": "application/json", "X-Api-Key": "dm-5db56ee14229-4daa8e87edef25a4b17c"}
)
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    print(json.dumps(data, indent=2)[:2000])
except urllib.error.HTTPError as e:
    print("STATUS:", e.code)
    print("BODY:", e.read().decode()[:500])
