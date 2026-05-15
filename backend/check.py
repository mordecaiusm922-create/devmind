lines = open("main.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "run_pipeline_from_json" in l and "await" in l:
        for j in range(max(0,i-5), i+5):
            print(f"{j+1}: {lines[j]}", end="")
        print("---")

