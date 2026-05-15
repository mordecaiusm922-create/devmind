import json, urllib.request

body = json.dumps({"prompt": "fix sql injection", "mode": "secure"}).encode()
req = urllib.request.Request(
    "https://devmind-2cej.onrender.com/analyze",
    data=body,
    headers={"Content-Type": "application/json", "X-Api-Key": "dm-5db56ee14229-4daa8e87edef25a4b17c"}
)
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read())
    print(json.dumps(data, indent=2)[:1500])
except Exception as e:
    print("Error:", e)
