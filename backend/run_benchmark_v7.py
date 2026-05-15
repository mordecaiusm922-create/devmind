import json, urllib.request, time

cases = json.load(open("ground_truth.json", encoding="utf-8-sig"))
api_key = "dm-5db56ee14229-4daa8e87edef25a4b17c"

BLOCK_KEYWORDS = [
    "sql injection", "eval(", "| bash", "curl https",
    "hardcoded", "secret_key", "disable ssl", "verify=false",
    "public-read", "wildcard", "iam wildcard", "privileged: true",
    "hostnetwork", "remove input validation", "force_destroy",
]

BLOCK_INTENTS = {"sql_injection_fix", "secret_fix", "hardcoded_secret_fix"}
REVISE_INTENTS = {"secure_fix", "auth_fix"}

TRIVIAL_SURFACES = {"documentation", "comment_only", "frontend_only", "test_only", "dependency_only"}

TRIVIAL_FILENAMES = {".md", ".css", ".txt", ".rst", "requirements.txt", "readme", "license"}

def detect_surface(prompt, files):
    filenames = [f.get("filename","").lower() for f in files]
    extensions = [f.rsplit(".",1)[-1] if "." in f else "" for f in filenames]
    
    if all(ext in {"md","txt","rst"} or "readme" in fn or "license" in fn for fn, ext in zip(filenames, extensions) if fn):
        return "documentation"
    if all(ext == "css" or "style" in fn for fn, ext in zip(filenames, extensions) if fn):
        return "frontend_only"
    if all("test" in fn or "spec" in fn for fn in filenames if fn):
        return "test_only"
    if all("requirements" in fn or "package" in fn or ext in {"txt","toml","lock"} for fn, ext in zip(filenames, extensions) if fn):
        return "dependency_only"
    if any(kw in prompt.lower() for kw in ["comment", "typo", "rename", "refactor"]):
        content = " ".join(f.get("content","") for f in files)
        if len(content) < 200:
            return "comment_only"
    return "runtime"

def keyword_block(prompt, files):
    text = (prompt + " " + " ".join(f.get("content","") for f in files)).lower()
    return any(kw in text for kw in BLOCK_KEYWORDS)

def infer_decision(data, prompt, files, mode):
    # 1. Infra siempre gana
    infra = data.get("infrastructure_security", {})
    if infra.get("block_merge") or infra.get("score", 0) >= 35:
        return "BLOCK"

    # 2. Surface detection
    surface = detect_surface(prompt, files)
    
    # 3. Trivial surface = APPROVE directo (sin keywords de bloqueo)
    if surface in TRIVIAL_SURFACES:
        if not keyword_block(prompt, files):
            return "APPROVE"

    # 4. Keywords de bloqueo
    if keyword_block(prompt, files):
        return "BLOCK"

    # 5. Intent
    intent = data.get("representation", {}).get("intent", {}).get("label", "")
    if intent in BLOCK_INTENTS:
        return "BLOCK"

    # 6. Modo balanced = APPROVE
    if mode == "balanced":
        return "APPROVE"

    # 7. Modo secure con intent de revision
    if intent in REVISE_INTENTS:
        return "REVISE"
    dec = data.get("decision", {})
    if isinstance(dec, dict):
        action = dec.get("action", "").upper()
        if action in {"NEEDS_VERIFICATION", "NEEDS_REPAIR", "REVISE"}:
            return "REVISE"

    # 8. Runtime secure con archivos de codigo = REVISE por defecto
    if mode == "secure" and surface == "runtime":
        filenames = [f.get("filename","").lower() for f in files]
        code_files = [f for f in filenames if f.endswith((".py",".js",".ts",".java",".go"))]
        if code_files:
            return "REVISE"

    return "APPROVE"

results = []
correct = 0
surface_stats = {}

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
        surface = detect_surface(case["prompt"], files)
        decision = infer_decision(data, case["prompt"], files, case["mode"])
        expected = case["expected"]
        match = decision == expected
        if match: correct += 1
        # Track por surface
        if surface not in surface_stats:
            surface_stats[surface] = {"correct": 0, "total": 0}
        surface_stats[surface]["total"] += 1
        if match: surface_stats[surface]["correct"] += 1
        status = "OK" if match else "FAIL"
        intent = data.get("representation", {}).get("intent", {}).get("label", "?")
        print(f"[{status}] {i+1:02d} | expected={expected:7} got={decision:7} | surface={surface:15} intent={intent:15} | {case['prompt'][:30]}")
        results.append({"prompt": case["prompt"], "expected": expected, "got": decision, "match": match, "surface": surface})
    except Exception as e:
        print(f"[ERR] {i+1:02d} | {e} | {case['prompt'][:30]}")
        results.append({"prompt": case["prompt"], "expected": case["expected"], "got": "ERROR", "match": False})
    time.sleep(2)

print(f"\n=== RESULTADO GLOBAL: {correct}/{len(cases)} ({100*correct//len(cases)}% accuracy) ===")
print("\n=== POR SURFACE ===")
for surface, stats in surface_stats.items():
    pct = 100 * stats["correct"] // stats["total"]
    print(f"  {surface:20} {stats['correct']}/{stats['total']} ({pct}%)")

json.dump(results, open("benchmark_results_v7.json", "w"), indent=2)
