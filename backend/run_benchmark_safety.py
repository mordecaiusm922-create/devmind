import json, urllib.request, time

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"
url = "https://devmind-2cej.onrender.com/safety-flow"

def infer_decision(data):
    decision = data.get("decision", {})
    if isinstance(decision, dict):
        action = decision.get("action", "").upper()
        merge_blocker = decision.get("merge_blocker", False)
        if merge_blocker or action in {"BLOCK", "REJECT"}:
            return "BLOCK"
        if action in {"NEEDS_VERIFICATION", "REVISE", "NEEDS_REPAIR"}:
            return "REVISE"
        if action == "APPROVE":
            return "APPROVE"
    infra = data.get("infrastructure_security", {})
    if infra.get("block_merge"):
        return "BLOCK"
    return "APPROVE"

results = []
correct = 0

for i, case in enumerate(cases):
    body = json.dumps({
        "prompt": case["prompt"],
        "mode": case["mode"],
        "files": case.get("files", [])
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json",
        "X-Api-Key": api_key
    })
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            data = json.loads(r.read())
        decision = infer_decision(data)
        expected = case["expected"]
        match = decision == expected
        if match: correct += 1
        status = "OK" if match else "FAIL"
        intent = data.get("representation", {}).get("intent", {}).get("label", "?")
        mb = data.get("decision", {}).get("merge_blocker", False) if isinstance(data.get("decision"), dict) else False
        print(f"[{status}] {i+1:02d} | expected={expected:7} got={decision:7} | intent={intent:20} mb={mb} | {case['prompt'][:40]}")
        results.append({"prompt": case["prompt"], "expected": expected, "got": decision, "match": match})
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:40]}")
        results.append({"prompt": case["prompt"], "expected": case["expected"], "got": "ERROR", "match": False})
    time.sleep(2)

print(f"\n=== RESULTADO: {correct}/{len(cases)} ({100*correct//len(cases)}% accuracy) ===")
json.dump(results, open("benchmark_results_safety.json", "w"), indent=2)
