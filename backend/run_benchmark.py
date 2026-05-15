import json, urllib.request, time

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"
url = "https://devmind-2cej.onrender.com/run"

def infer_decision(data):
    # Si infra_block -> BLOCK
    infra = data.get("infrastructure_security", {})
    if infra.get("block_merge"):
        return "BLOCK"
    if infra.get("score", 0) >= 35:
        return "BLOCK"

    # Por intent + summary
    intent = data.get("intent", {}).get("label", "")
    summary = data.get("summary", {})
    security = float(summary.get("security", 0) or 0)
    merge_blocker = summary.get("merge_blocker", False)

    if merge_blocker or security >= 0.9:
        return "BLOCK"
    if security >= 0.7:
        return "REVISE"

    # Por intent
    block_intents = {"sql_injection_fix", "secret_fix", "infra_fix"}
    revise_intents = {"general_fix", "auth_fix"}
    approve_intents = {"docs_only", "style_fix", "test_fix"}

    if intent in block_intents and security >= 0.6:
        return "BLOCK"
    if intent in approve_intents or security < 0.4:
        return "APPROVE"
    return "REVISE"

results = []
correct = 0

for i, case in enumerate(cases):
    body = json.dumps({"prompt": case["prompt"], "mode": case["mode"]}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "X-Api-Key": api_key
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        decision = infer_decision(data)
        expected = case["expected"]
        match = decision == expected
        if match:
            correct += 1
        status = "OK" if match else "FAIL"
        intent = data.get("intent", {}).get("label", "?")
        sec = data.get("summary", {}).get("security", "?")
        print(f"[{status}] {i+1:02d} | expected={expected:7} got={decision:7} | intent={intent:20} sec={sec} | {case['prompt'][:40]}")
        results.append({"prompt": case["prompt"], "expected": expected, "got": decision, "match": match})
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:40]}")
        results.append({"prompt": case["prompt"], "expected": case["expected"], "got": "ERROR", "match": False})
    time.sleep(1)

print(f"\n=== RESULTADO: {correct}/{len(cases)} ({100*correct//len(cases)}% accuracy) ===")
json.dump(results, open("benchmark_results.json", "w"), indent=2)
