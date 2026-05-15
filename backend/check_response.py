import json, urllib.request

body = json.dumps({"prompt": "update README.md", "mode": "balanced"}).encode()
req = urllib.request.Request(
    "https://devmind-2cej.onrender.com/run",
    data=body,
    headers={"Content-Type": "application/json", "X-Api-Key": "dm-5db56ee14229-4daa8e87edef25a4b17c"}
)
with urllib.request.urlopen(req, timeout=30) as r:
    data = json.loads(r.read())

print("decision field:", data.get("decision"))
print("tipo:", type(data.get("decision")))
print(json.dumps(data, indent=2)[:1000])
