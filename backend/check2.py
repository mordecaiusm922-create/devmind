lines = open("pipeline.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "run_pipeline_from_json" in l and "def " in l:
        for j in range(i, min(i+30, len(lines))):
            print(f"{j+1}: {lines[j]}", end="")
        break

