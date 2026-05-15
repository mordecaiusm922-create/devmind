lines = open("pipeline.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "best_candidate = repair_result.candidate" in l or "repair_result.candidate" in l:
        for j in range(max(0,i-5), min(i+8, len(lines))):
            print(f"{j+1}: {lines[j]}", end="")
        print("---")

