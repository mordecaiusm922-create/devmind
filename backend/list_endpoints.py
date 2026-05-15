lines = open("main.py", encoding="utf-8").readlines()
for i, l in enumerate(lines):
    if "@app." in l and ("post" in l.lower() or "get" in l.lower()):
        print(f"{i+1}: {l}", end="")

