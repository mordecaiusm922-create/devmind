# -*- coding: utf-8 -*-
# lazy import to avoid slow startup

SUPPORTED = ["python", "javascript", "typescript"]

def get_ts_parser(lang: str):
    from tree_sitter_languages import get_parser as _get_parser
    lang = lang.lower()
    if lang not in SUPPORTED:
        lang = "python"
    return _get_parser(lang)

def detect_language(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower()
    return {"py": "python", "js": "javascript", "ts": "typescript"}.get(ext, "python")

def get_functions(node, code_bytes):
    functions = []
    def traverse(n):
        if n.type in ["function_definition", "function_declaration", "method_definition"]:
            name_node = n.child_by_field_name("name")
            name = name_node.text.decode() if name_node else "anonymous"
            functions.append({
                "name": name,
                "start": n.start_point[0],
                "end": n.end_point[0],
                "code": code_bytes[n.start_byte:n.end_byte].decode(errors="replace")
            })
        for child in n.children:
            traverse(child)
    traverse(node)
    return functions

def filter_changed_functions(functions, changed_lines):
    result = []
    for f in functions:
        for line in changed_lines:
            if f["start"] <= line <= f["end"]:
                result.append(f)
                break
    return result

def extract_calls(node):
    calls = []
    def traverse(n):
        if n.type == "call":
            calls.append(n.text.decode(errors="replace"))
        for c in n.children:
            traverse(c)
    traverse(node)
    return list(set(calls))

def _clean_diff(patch: str) -> tuple:
    clean_lines = []
    changed = []
    line_num = 0
    import re
    for line in patch.split(chr(10)):
        if line.startswith('@@'):
            m = re.search(r'\+(\d+)', line)
            if m:
                line_num = int(m.group(1))
        elif line.startswith('+') and not line.startswith('+++'):
            clean_lines.append(line[1:])
            changed.append(line_num)
            line_num += 1
        elif line.startswith('-') or line.startswith('---'):
            pass
        else:
            clean_lines.append(line)
            line_num += 1
    return chr(10).join(clean_lines), changed

def parse_pr_file(filename: str, code: str, changed_lines: list) -> dict:
    code, changed_lines = _clean_diff(code)
    lang = detect_language(filename)
    parser = get_ts_parser(lang)
    code_bytes = bytes(code, "utf-8")
    tree = parser.parse(code_bytes)
    all_functions = get_functions(tree.root_node, code_bytes)
    changed_functions = filter_changed_functions(all_functions, changed_lines)
    calls = []
    for f in changed_functions:
        f_bytes = bytes(f["code"], "utf-8")
        f_tree = parser.parse(f_bytes)
        calls.extend(extract_calls(f_tree.root_node))
    return {
        "language": lang,
        "functions_changed": [{"name": f["name"], "lines": [f["start"], f["end"]]} for f in changed_functions],
        "calls": list(set(calls))
    }
