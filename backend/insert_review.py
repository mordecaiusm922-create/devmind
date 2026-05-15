lines = open("main.py", encoding="utf-8").readlines()

# Insertar antes de /sandbox
insert_at = None
for i, l in enumerate(lines):
    if "@app.post(\"/sandbox\"" in l:
        insert_at = i
        break

if insert_at is None:
    print("ERROR: /sandbox no encontrado")
else:
    review_code = [
        "\n",
        "@app.post(\"/review\", dependencies=[Depends(_require_api_key)])\n",
        "async def review_endpoint(payload: dict):\n",
        "    from infra_analyzer import analyze_infra\n",
        "    from policy_engine import policy_decision\n",
        "    files = list(payload.get(\"files\", []) or [])\n",
        "    prompt = str(payload.get(\"prompt\", \"\"))\n",
        "    mode = str(payload.get(\"mode\", \"secure\"))\n",
        "    infra = analyze_infra(files) if files else None\n",
        "    infra_score = infra.risk_score if infra else 0\n",
        "    infra_block = infra.block_merge if infra else False\n",
        "    infra_findings = [{\"rule_id\": f.rule_id, \"severity\": f.severity, \"title\": f.title, \"surface\": f.surface, \"fix_hint\": f.fix_hint} for f in infra.findings] if infra else []\n",
        "    intent_label = \"general_fix\"\n",
        "    intent_confidence = 0.0\n",
        "    safety_action = \"\"\n",
        "    try:\n",
        "        import httpx\n",
        "        async with httpx.AsyncClient(timeout=30) as client:\n",
        "            sf = await client.post(\"https://devmind-2cej.onrender.com/safety-flow\",\n",
        "                json={\"prompt\": prompt, \"mode\": mode, \"files\": files},\n",
        "                headers={\"Content-Type\": \"application/json\", \"X-Api-Key\": payload.get(\"_api_key\", \"\")})\n",
        "            if sf.status_code == 200:\n",
        "                sd = sf.json()\n",
        "                intent_label = sd.get(\"representation\", {}).get(\"intent\", {}).get(\"label\", \"general_fix\")\n",
        "                intent_confidence = sd.get(\"representation\", {}).get(\"intent\", {}).get(\"confidence\", 0.0)\n",
        "                dec = sd.get(\"decision\", {})\n",
        "                safety_action = dec.get(\"action\", \"\").upper() if isinstance(dec, dict) else \"\"\n",
        "    except Exception:\n",
        "        pass\n",
        "    policy = policy_decision(prompt=prompt, files=files, mode=mode,\n",
        "        intent_label=intent_label, infra_block=infra_block,\n",
        "        infra_score=infra_score, safety_action=safety_action)\n",
        "    return {\n",
        "        \"decision\": policy[\"decision\"],\n",
        "        \"reason\": policy[\"reason\"],\n",
        "        \"surface\": policy[\"surface\"],\n",
        "        \"intent\": {\"label\": intent_label, \"confidence\": intent_confidence},\n",
        "        \"infrastructure_security\": {\"score\": infra_score, \"block_merge\": infra_block, \"findings\": infra_findings},\n",
        "        \"merge_blocker\": policy[\"decision\"] == \"BLOCK\",\n",
        "    }\n",
        "\n",
    ]
    lines[insert_at:insert_at] = review_code
    open("main.py", "w", encoding="utf-8").writelines(lines)
    print(f"OK - /review insertado en linea {insert_at+1}")
