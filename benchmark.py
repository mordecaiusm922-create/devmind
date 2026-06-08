import httpx
h = {"Content-Type": "application/json", "X-Api-Key": "dm-5db56ee14229-4daa8e87edef25a4b17c"}
prs = [
    ("psf/black", 3864, "ALLOW"),
    ("psf/black", 5141, "ALLOW"),
    ("django/django", 17379, "ALLOW"),
    ("psf/requests", 6710, "REVIEW"),
    ("pallets/flask", 5992, "ALLOW"),
]
for repo, pr, expected in prs:
    r = httpx.post("https://devmind-2cej.onrender.com/analyze-pr", headers=h, json={"repo": repo, "pr_number": pr}, timeout=60)
    d = r.json()
    dec = d.get("decision", {}).get("action", "?")
    score = d.get("risk", {}).get("score", 0)
    ok = "OK" if dec == expected else f"FAIL expected={expected}"
    print(f"{repo}#{pr} score={score} {dec} {ok}")
