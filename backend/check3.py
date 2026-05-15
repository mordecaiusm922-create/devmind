lines = open("pipeline.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "def task_from_json" in l:
        for j in range(i, min(i+25, len(lines))):
            print(f"{j+1}: {lines[j]}", end="")
        break

