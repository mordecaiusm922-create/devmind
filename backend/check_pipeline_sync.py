path = r"C:\Users\usuario\Downloads\devmind\devmind\backend\main.py"

with open(path, "r", encoding="utf-8") as f:
    content = f.read()

idx = content.find("get_pr_data, repo, pr_number")
print(repr(content[idx-20:idx+200]))
