lines = open("pipeline.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "analyze_infra" in l:
        for j in range(max(0,i-3), min(i+5, len(lines))):
            print(f"{j+1}: {lines[j]}", end="")
        print("---")

