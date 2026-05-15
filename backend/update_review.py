lines = open("main.py", encoding="utf-8").readlines()

# Encontrar el endpoint /review que agregamos antes y reemplazarlo completo
start = None
end = None
for i, l in enumerate(lines):
    if "@app.post(\"/review\"" in l:
        start = i
    if start and i > start and "@app." in l and i > start + 2:
        end = i
        break

if start is None:
    print("ERROR: /review endpoint no encontrado")
else:
    review_code = """
@app.post("/review", dependencies=[Depends(_require_api_key)])
async def review_endpoint(payload: dict):
    from infra_analyzer import analyze_infra
    from policy_engine import policy_decision

    files = list(payload.get("files", []) or [])
    prompt = str(payload.get("prompt", ""))
    mode = str(payload.get("mode", "secure"))

    # 1. Infra analysis
    infra = analyze_infra(files) if files else None
    infra_score = infra.risk_score if infra else 0
    infra_block = infra.block_merge if infra else False
    infra_findings = [
        {"rule_id": f.rule_id, "severity": f.severity, "title": f.title,
         "surface": f.surface, "file": f.file, "fix_hint": f.fix_hint}
        for f in infra.findings
    ] if infra else []

    # 2. Safety flow for intent + risk signals
    import json as _json
    import httpx
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            sf_resp = await client.post(
                "http://localhost:8000/safety-flow",
                json={"prompt": prompt, "mode": mode, "files": files},
                headers={"X-Api-Key": payload.get("_api_key", "")}
            )
            sf_data = sf_resp.json() if sf_resp.status_code == 200 else {}
    except Exception:
        sf_data = {}

    intent_label = sf_data.get("representation", {}).get("intent", {}).get("label", "general_fix")
    intent_confidence = sf_data.get("representation", {}).get("intent", {}).get("confidence", 0.0)
    sf_decision = sf_data.get("decision", {})
    safety_action = sf_decision.get("action", "").upper() if isinstance(sf_decision, dict) else ""

    # 3. Policy engine
    policy = policy_decision(
        prompt=prompt,
        files=files,
        mode=mode,
        intent_label=intent_label,
        infra_block=infra_block,
        infra_score=infra_score,
        safety_action=safety_action,
    )

    return {
        "decision": policy["decision"],
        "reason": policy["reason"],
        "surface": policy["surface"],
        "intent": {"label": intent_label, "confidence": intent_confidence},
        "infrastructure_security": {
            "score": infra_score,
            "block_merge": infra_block,
            "findings": infra_findings,
        },
        "merge_blocker": policy["decision"] == "BLOCK",
    }

"""
    lines[start:end] = [review_code, lines[end] if end else ""]
    open("main.py", "w", encoding="utf-8").writelines(lines)
    print(f"OK - /review actualizado (lineas {start+1} a {end})")
