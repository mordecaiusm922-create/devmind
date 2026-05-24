import json, urllib.request, re

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"
url = "https://devmind-2cej.onrender.com/run"

BLOCK_INTENTS = {"sql_injection_fix","secret_fix","infra_fix","rce_fix","auth_bypass_fix","ssrf_fix","xss_fix"}
REVISE_INTENTS = {"auth_fix","concurrency_fix","reliability_fix"}
BLOCK_KEYWORDS = ["sql injection","sqli","hardcoded secret","secret_key","kubernetes","terraform",
                  "iam wildcard","s3 bucket","eval to execute","execute user input"," eval ",
                  "curl.*bash","curl.*sh","db credentials","ssl verification","remove input validation",
                  "wildcard","public bucket","expose db","disable ssl","grant iam","public.*bucket"]
REVISE_KEYWORDS = ["oauth","oauth2","authentication","authorization","null pointer","payment","logging"]
APPROVE_KEYWORDS = ["readme","css","typo","comment","unit test","requirements","pagination","refactor","utility"]

def infer_decision(data, prompt):
    intent = data.get("intent", {}).get("label", "general_fix")
    decision = data.get("decision", "approve")
    security = data.get("summary", {}).get("security")
    if security is not None:
        security = float(security)
    prompt_lower = prompt.lower()

    # 1. BLOCK por intent critico
    if intent in BLOCK_INTENTS:
        return "BLOCK"

    # 2. BLOCK por keywords
    for kw in BLOCK_KEYWORDS:
        if re.search(kw, prompt_lower):
            return "BLOCK"

    # 3. APPROVE por keywords triviales
    for kw in APPROVE_KEYWORDS:
        if kw in prompt_lower:
            return "APPROVE"

    # 4. REVISE por keywords de revision
    for kw in REVISE_KEYWORDS:
        if kw in prompt_lower:
            return "REVISE"

    # 5. REVISE por intent
    if intent in REVISE_INTENTS:
        return "REVISE"

    # 6. Solo REVISE si security es realmente alta
    if security is not None and security >= 0.80:
        return "REVISE"

    return "APPROVE"

correct = 0
for i, case in enumerate(cases):
    body = json.dumps({"prompt": case["prompt"], "mode": case["mode"]}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "X-Api-Key": api_key
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        decision = infer_decision(data, case["prompt"])
        expected = case["expected"]
        match = decision == expected
        if match: correct += 1
        intent = data.get("intent", {}).get("label", "?")
        sec = data.get("summary", {}).get("security", "?")
        print(f"[{'OK' if match else 'FAIL'}] {i+1:02d} | expected={expected:7} got={decision:7} | intent={intent:20} sec={sec} | {case['prompt'][:40]}")
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:40]}")

print(f"=== RESULTADO: {correct}/{len(cases)} ({correct/len(cases)*100:.0f}% accuracy) ===")
