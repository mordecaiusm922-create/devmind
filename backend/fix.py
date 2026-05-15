lines = open("pipeline.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "asdict(score) for cid, score in self.evaluation.scores.items()}" in l:
        print(f"Encontrado linea {i+1}")
        lines[i] = lines[i].replace(".items()}", ".items() if score is not None}")
        break
open("pipeline.py", "w", encoding="utf-8").writelines(lines)
print("OK")
