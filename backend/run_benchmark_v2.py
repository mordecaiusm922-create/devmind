import json, urllib.request, time

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"
url = "https://devmind-2cej.onrender.com/safety-flow"

def infer_decision(data, mode):
    decision = data.get("decision", {})
    action = ""
    merge_blocker = False
    if isinstance(decision, dict):
        action = decision.get("action", "").upper()
        merge_blocker = decision.get("merge_blocker", False)

    # Infra siempre gana
    infra = data.get("infrastructure_security", {})
    if infra.get("block_merge") or infra.get("score", 0) >= 35:
        return "BLOCK"

    intent = data.get("representation", {}).get("intent", {}).get("label", "")
    selected = data.get("selected", {}) or {}
    security = float(selected.get("security", 0) or 0)
    critical_violations = selected.get("critical_violations", [])
    violations = selected.get("violations", [])

    # En modo balanced — solo bloquear si hay violaciones criticas reales
    if mode == "balanced":
        if critical_violations:
            return "BLOCK"
        if action in {"BLOCK", "REJECT"}:
            return "REVISE"
        if action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR"}:
            return "REVISE"
        return "APPROVE"

    # En modo secure
    if critical_violations or security < 0.5:
        return "BLOCK"
    if merge_blocker and action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR"}:
        if intent in {"secure_fix", "sql_injection_fix", "secret_fix", "infra_fix"}:
            return "BLOCK"
        return "REVISE"
    if action in {"BLOCK", "REJECT"}:
        return "BLOCK"
    if action in {"NEEDS_VERIFICATION", "REVISE", "NEEDS_REPAIR"}:
        return "REVISE"
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
        decision = infer_decision(data, case["mode"])
        expected = case["expected"]
        match = decision == expected
        if match: correct += 1
        status = "OK" if match else "FAIL"
        intent = data.get("representation", {}).get("intent", {}).get("label", "?")
        sel = data.get("selected", {}) or {}
        sec = sel.get("security", "?")
        cv = len(sel.get("critical_violations", []))
        print(f"[{status}] {i+1:02d} | expected={expected:7} got={decision:7} | intent={intent:20} sec={sec} cv={cv} | {case['prompt'][:35]}")
        results.append({"prompt": case["prompt"], "expected": expected, "got": decision, "match": match})
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:35]}")
        results.append({"prompt": case["prompt"], "expected": case["expected"], "got": "ERROR", "match": False})
    time.sleep(2)

print(f"\n=== RESULTADO: {correct}/{len(cases)} ({100*correct//len(cases)}% accuracy) ===")
json.dump(results, open("benchmark_results_v2.json", "w"), indent=2)
