from __future__ import annotations

import ast
import json
import re
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


DATA_DIR = Path("data")
GRAPH_DIR = DATA_DIR / "graph"

GRAPH_DIR.mkdir(parents=True, exist_ok=True)

IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([A-Za-z0-9_.]+)\s+import\s+(.+)|import\s+(.+))",
    re.MULTILINE,
)

CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\(")


def _sanitize_repo(repo: str) -> str:
    return repo.replace("/", "__").replace(":", "__")


def _graph_path(repo: str) -> Path:
    return GRAPH_DIR / f"{_sanitize_repo(repo)}.json"


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _safe_parse_python(code: str) -> ast.AST | None:
    try:
        return ast.parse(code)
    except SyntaxError:
        return None
    except Exception:
        return None


def _file_kind(path: str) -> str:
    lower = path.lower()
    if lower.endswith((".py", ".pyi")):
        return "python"
    if lower.endswith((".js", ".jsx", ".ts", ".tsx")):
        return "javascript"
    if lower.endswith((".yml", ".yaml")):
        return "yaml"
    if lower.endswith(".json"):
        return "json"
    if lower.endswith(".toml"):
        return "toml"
    if lower.endswith(".sh"):
        return "shell"
    return "other"


def _extract_python_imports(code: str) -> set[str]:
    tree = _safe_parse_python(code)
    if tree is None:
        return set()

    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                imports.add(module)
            for alias in node.names:
                if module:
                    imports.add(f"{module}.{alias.name}")
                else:
                    imports.add(alias.name)

    return imports


def _extract_python_calls(code: str) -> set[str]:
    tree = _safe_parse_python(code)
    if tree is None:
        return set()

    calls: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                calls.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                calls.add(fn.attr)

    return calls


def _extract_generic_calls(code: str) -> set[str]:
    return set(CALL_RE.findall(code or ""))


def _extract_yaml_refs(code: str) -> set[str]:
    refs: set[str] = set()
    for line in (code or "").splitlines():
        if "uses:" in line:
            refs.add(line.strip())
        if "run:" in line:
            refs.add(line.strip())
        if "secrets." in line or "github." in line or "env." in line:
            refs.add(line.strip())
    return refs


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    path: str | None = None
    name: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    weight: float = 1.0
    metadata: dict[str, Any] | None = None


def build_repo_graph(pr_data: dict[str, Any]) -> dict[str, Any]:
    """
    Build a lightweight dependency / risk graph from PR data.

    Expected pr_data shape:
      {
        "repo": "...",
        "files": [
          {"filename": "...", "diff": "...", "raw_patch": "...", "status": "..."}
        ]
      }
    """
    repo = str(pr_data.get("repo", "unknown/repo"))
    files = pr_data.get("files", []) or []

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []

    repo_node_id = f"repo:{repo}"
    nodes[repo_node_id] = Node(
        id=repo_node_id,
        kind="repo",
        name=repo,
        metadata={"repo": repo},
    )

    for f in files:
        filename = str(f.get("filename", ""))
        if not filename:
            continue

        file_id = f"file:{filename}"
        status = str(f.get("status", "modified"))
        diff = str(f.get("diff") or "")
        raw_patch = str(f.get("raw_patch") or "")
        code = raw_patch or diff
        kind = _file_kind(filename)

        nodes[file_id] = Node(
            id=file_id,
            kind="file",
            path=filename,
            name=filename,
            metadata={
                "status": status,
                "kind": kind,
                "additions": f.get("additions", 0),
                "deletions": f.get("deletions", 0),
                "truncated": bool(f.get("truncated", False)),
            },
        )

        edges.append(
            Edge(
                source=repo_node_id,
                target=file_id,
                relation="contains",
                weight=1.0,
                metadata={"status": status},
            )
        )

        if kind == "python":
            imports = _extract_python_imports(code)
            calls = _extract_python_calls(code)
            generic_calls = _extract_generic_calls(code)

            for imp in sorted(imports):
                mod_id = f"module:{imp}"
                if mod_id not in nodes:
                    nodes[mod_id] = Node(id=mod_id, kind="module", name=imp)
                edges.append(
                    Edge(
                        source=file_id,
                        target=mod_id,
                        relation="imports",
                        weight=0.8,
                        metadata={"file": filename},
                    )
                )

            for call in sorted(calls | generic_calls):
                if not call:
                    continue
                call_id = f"call:{call}"
                if call_id not in nodes:
                    nodes[call_id] = Node(id=call_id, kind="call", name=call)
                edges.append(
                    Edge(
                        source=file_id,
                        target=call_id,
                        relation="calls",
                        weight=0.5,
                        metadata={"file": filename},
                    )
                )

        elif kind == "yaml":
            refs = _extract_yaml_refs(code)
            for ref in sorted(refs):
                ref_id = f"yaml_ref:{hash(ref)}"
                if ref_id not in nodes:
                    nodes[ref_id] = Node(
                        id=ref_id,
                        kind="yaml_ref",
                        name=ref[:120],
                        metadata={"ref": ref, "file": filename},
                    )
                edges.append(
                    Edge(
                        source=file_id,
                        target=ref_id,
                        relation="references",
                        weight=0.7,
                        metadata={"file": filename},
                    )
                )

        else:
            calls = _extract_generic_calls(code)
            for call in sorted(calls):
                call_id = f"call:{call}"
                if call_id not in nodes:
                    nodes[call_id] = Node(id=call_id, kind="call", name=call)
                edges.append(
                    Edge(
                        source=file_id,
                        target=call_id,
                        relation="calls",
                        weight=0.4,
                        metadata={"file": filename},
                    )
                )

    graph = {
        "repo": repo,
        "nodes": [asdict(n) for n in nodes.values()],
        "edges": [asdict(e) for e in edges],
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "file_count": len(files),
        },
    }

    return graph


def build_dependency_index(pr_data: dict[str, Any]) -> dict[str, Any]:
    """
    Build a compact index for downstream retrieval / scoring.
    """
    graph = build_repo_graph(pr_data)

    adjacency: dict[str, list[str]] = defaultdict(list)
    incoming: dict[str, list[str]] = defaultdict(list)

    for edge in graph["edges"]:
        s = edge["source"]
        t = edge["target"]
        adjacency[s].append(t)
        incoming[t].append(s)

    return {
        "repo": graph["repo"],
        "graph": graph,
        "adjacency": dict(adjacency),
        "incoming": dict(incoming),
    }


def find_high_risk_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Identify nodes most likely to matter for security analysis.
    """
    risky: list[dict[str, Any]] = []
    for node in graph.get("nodes", []):
        kind = node.get("kind")
        name = (node.get("name") or "").lower()
        path = (node.get("path") or "").lower()

        score = 0.0
        reasons: list[str] = []

        if "secret" in name or "token" in name or "key" in name or "cred" in name:
            score += 0.6
            reasons.append("secret_surface")

        if ".github/workflows" in path:
            score += 0.7
            reasons.append("workflow_file")

        if "config" in path or "settings" in path:
            score += 0.3
            reasons.append("config_surface")

        if kind == "call" and name in {"eval", "exec", "subprocess", "system", "open"}:
            score += 0.5
            reasons.append("dangerous_call")

        if score > 0:
            risky.append(
                {
                    "node": node,
                    "score": round(min(score, 1.0), 4),
                    "reasons": reasons,
                }
            )

    risky.sort(key=lambda x: x["score"], reverse=True)
    return risky


def shortest_path(graph: dict[str, Any], source: str, target: str) -> list[str]:
    """
    Breadth-first shortest path over the directed graph.
    """
    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in graph.get("edges", []):
        adjacency[edge["source"]].append(edge["target"])

    queue = deque([(source, [source])])
    visited = {source}

    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        for nxt in adjacency.get(node, []):
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + [nxt]))

    return []


def summarize_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """
    Human- and machine-friendly summary.
    """
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    kinds = Counter(node.get("kind", "unknown") for node in nodes)
    rels = Counter(edge.get("relation", "unknown") for edge in edges)

    return {
        "repo": graph.get("repo"),
        "stats": graph.get("stats", {}),
        "node_kinds": dict(kinds),
        "edge_relations": dict(rels),
        "top_risky_nodes": find_high_risk_nodes(graph)[:10],
    }


def save_graph(repo: str, graph: dict[str, Any]) -> Path:
    """
    Persist graph to disk.
    """
    path = _graph_path(repo)
    with path.open("w", encoding="utf-8") as f:
        json.dump(graph, f, ensure_ascii=False, indent=2)
    return path


def load_graph(repo: str) -> dict[str, Any] | None:
    path = _graph_path(repo)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def build_and_save_repo_graph(pr_data: dict[str, Any]) -> dict[str, Any]:
    graph = build_repo_graph(pr_data)
    save_graph(str(pr_data.get("repo", "unknown/repo")), graph)
    return graph