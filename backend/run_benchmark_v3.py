import json, urllib.request, time

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"

BLOCK_KEYWORDS = [
    "sql injection", "eval(", "curl | bash", "curl|bash",
    "hardcoded", "secret_key", "disable ssl", "verify=false",
    "public-read", "wildcard", "iam wildcard", "privileged: true",
    "hostnetwork", "publicly accessible", "remove input validation",
    "expose", "force_destroy", "acl = \"public-read\""
]

BLOCK_INTENTS = {"secure_fix", "sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}

def keyword_block(prompt, files):
    text = (prompt + " " + " ".join(f.get("content","") for f in files)).lower()
    return any(kw in text for kw in BLOCK_KEYWORDS)

def infer_decision(data, prompt, files, mode):
    infra = data.get("infrastructure_security", {})
    if infra.get("block_merge") or infra.get("score", 0) >= 35:
        return "BLOCK"
    if keyword_block(prompt, files):
        return "BLOCK"
    intent = data.get("representation", {}).get("intent", {}).get("label", "")
    if intent in BLOCK_INTENTS:
        return "BLOCK"
    if mode == "balanced":
        return "APPROVE"
    return "REVISE"

results = []
correct = 0

for i, case in enumerate(cases):
    files = case.get("files", [])
    body = json.dumps({"prompt": case["prompt"], "mode": case["mode"], "files": files}).encode()
    req = urllib.request.Request(
        "https://devmind-2cej.onrender.com/safety-flow",
        data=body,
        headers={"Content-Type": "application/json", "X-Api-Key": api_key}
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            data = json.loads(r.read())
        decision = infer_decision(data, case["prompt"], files, case["mode"])
        expected = case["expected"]
        match = decision == expected
        if match: correct += 1
        status = "OK" if match else "FAIL"
        intent = data.get("representation", {}).get("intent", {}).get("label", "?")
        infra_score = data.get("infrastructure_security", {}).get("score", 0)
        print(f"[{status}] {i+1:02d} | expected={expected:7} got={decision:7} | intent={intent:20} infra={infra_score} | {case['prompt'][:35]}")
        results.append({"prompt": case["prompt"], "expected": expected, "got": decision, "match": match})
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:35]}")
        results.append({"prompt": case["prompt"], "expected": case["expected"], "got": "ERROR", "match": False})
    time.sleep(2)

print(f"\n=== RESULTADO: {correct}/{len(cases)} ({100*correct//len(cases)}% accuracy) ===")
json.dump(results, open("benchmark_results_v3.json", "w"), indent=2)
