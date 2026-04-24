import os
import re
import requests
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Files that carry zero semantic signal — skip diff, keep filename only
NOISE_PATTERNS = [
    r"package-lock\.json$",
    r"yarn\.lock$",
    r"pnpm-lock\.yaml$",
    r"poetry\.lock$",
    r"Pipfile\.lock$",
    r"Gemfile\.lock$",
    r"composer\.lock$",
    r"\.snap$",            # jest snapshots
    r"\.min\.(js|css)$",  # minified assets
    r"dist/",
    r"build/",
    r"__pycache__/",
    r"\.pyc$",
    r"\.map$",            # source maps
    r"\.ico$",
    r"\.png$",
    r"\.jpg$",
    r"\.svg$",
    r"CHANGELOG\.md$",
]

# Char budget per file diff (rough 1:4 char-to-token ratio for code)
FILE_CHAR_BUDGET = 3_000
# Total budget for all diffs sent to the model
TOTAL_DIFF_BUDGET = 24_000
# A PR is "large" if it changes more files than this
LARGE_PR_FILE_THRESHOLD = 20


def get_pr_data(repo: str, pr_number: int) -> dict:
    """Fetches PR metadata, per-file diffs, and review comments."""

    # ── 1. PR metadata ────────────────────────────────────────────────────────
    pr_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    pr_resp = requests.get(pr_url, headers=HEADERS)
    if pr_resp.status_code != 200:
        raise Exception(
            f"GitHub API error {pr_resp.status_code}: "
            f"{pr_resp.json().get('message', 'unknown error')}"
        )
    pr = pr_resp.json()

    # ── 2. Per-file diffs (richer than the single diff endpoint) ──────────────
    files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"
    files_resp = requests.get(files_url, headers=HEADERS, params={"per_page": 100})
    raw_files = files_resp.json() if files_resp.status_code == 200 else []

    processed_files = _process_files(raw_files)

    # ── 3. Review comments (inline code comments — highest signal density) ────
    rc_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"
    rc_resp = requests.get(rc_url, headers=HEADERS, params={"per_page": 50})
    review_comments = []
    if rc_resp.status_code == 200:
        for c in rc_resp.json()[:15]:
            review_comments.append({
                "user": c["user"]["login"],
                "path": c.get("path", ""),
                "body": c["body"][:400],
            })

    # ── 4. Issue-level comments (PR conversation) ─────────────────────────────
    ic_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    ic_resp = requests.get(ic_url, headers=HEADERS, params={"per_page": 20})
    issue_comments = []
    if ic_resp.status_code == 200:
        for c in ic_resp.json()[:8]:
            issue_comments.append({
                "user": c["user"]["login"],
                "body": c["body"][:400],
            })

    # ── 5. Commit messages (intent context) ───────────────────────────────────
    commits_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/commits"
    commits_resp = requests.get(commits_url, headers=HEADERS, params={"per_page": 30})
    commit_messages = []
    if commits_resp.status_code == 200:
        for c in commits_resp.json():
            msg = c["commit"]["message"].split("\n")[0]
            commit_messages.append(msg)

    return {
        "title": pr["title"],
        "body": pr.get("body") or "",
        "author": pr["user"]["login"],
        "base_branch": pr["base"]["ref"],
        "head_branch": pr["head"]["ref"],
        "changed_files": pr["changed_files"],
        "additions": pr["additions"],
        "deletions": pr["deletions"],
        "state": pr["state"],
        "created_at": pr["created_at"],
        "merged_at": pr.get("merged_at"),
        "files": processed_files,
        "review_comments": review_comments,
        "issue_comments": issue_comments,
        "commit_messages": commit_messages,
        "is_large_pr": pr["changed_files"] > LARGE_PR_FILE_THRESHOLD,
    }


# ── Diff preprocessing ────────────────────────────────────────────────────────

def _process_files(raw_files: list) -> list:
    """
    Cleans, filters, and budget-allocates diffs across all changed files.
    Orders by semantic signal density (noise last, highest churn first).
    """
    if not raw_files:
        return []

    classified = []
    for f in raw_files:
        filename = f.get("filename", "")
        classified.append({
            "filename": filename,
            "status": f.get("status", "modified"),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "is_noise": _is_noise_file(filename),
            "raw_patch": f.get("patch", ""),
        })

    # Noise files last; within each group, highest churn first
    classified.sort(key=lambda f: (f["is_noise"], -(f["additions"] + f["deletions"])))

    result = []
    total_chars_used = 0

    for f in classified:
        if f["is_noise"]:
            result.append({
                "filename": f["filename"],
                "status": f["status"],
                "additions": f["additions"],
                "deletions": f["deletions"],
                "diff": None,
                "skipped_reason": "generated/lockfile",
            })
            continue

        if total_chars_used >= TOTAL_DIFF_BUDGET:
            result.append({
                "filename": f["filename"],
                "status": f["status"],
                "additions": f["additions"],
                "deletions": f["deletions"],
                "diff": None,
                "skipped_reason": "budget_exceeded",
            })
            continue

        cleaned = _clean_patch(f["raw_patch"])
        remaining = TOTAL_DIFF_BUDGET - total_chars_used
        truncated, was_truncated = _smart_truncate(cleaned, min(FILE_CHAR_BUDGET, remaining))
        total_chars_used += len(truncated)

        result.append({
            "filename": f["filename"],
            "status": f["status"],
            "additions": f["additions"],
            "deletions": f["deletions"],
            "raw_patch": f["raw_patch"],
            "diff": truncated,
            "truncated": was_truncated,
            "skipped_reason": None,
        })

    return result


def _is_noise_file(filename: str) -> bool:
    return any(re.search(pattern, filename) for pattern in NOISE_PATTERNS)


def _clean_patch(patch: str) -> str:
    """
    Strips lines with no semantic content:
    - git diff metadata headers
    - lines that are purely whitespace changes
    Preserves hunk headers (@@ lines) for positional context.
    """
    if not patch:
        return ""

    lines = patch.splitlines()
    cleaned = []

    for line in lines:
        if line.startswith("@@"):
            cleaned.append(line)
            continue
        if line.startswith(("diff --git", "index ", "--- ", "+++ ",
                             "similarity index", "rename from", "rename to",
                             "new file mode", "deleted file mode",
                             "old mode", "new mode")):
            continue
        # Skip lines where the actual content (ignoring the +/- prefix) is blank
        content = line[1:] if line and line[0] in ("+", "-", " ") else line
        if not content.strip():
            continue
        cleaned.append(line)

    return "\n".join(cleaned)


def _smart_truncate(text: str, char_limit: int) -> tuple[str, bool]:
    """
    Cuts at a hunk boundary (@@ line) rather than mid-line,
    so the model never receives a structurally broken diff.
    """
    if len(text) <= char_limit:
        return text, False

    cutoff = text.rfind("\n@@", 0, char_limit)
    if cutoff == -1:
        cutoff = text.rfind("\n", 0, char_limit)
    if cutoff == -1:
        cutoff = char_limit

    return text[:cutoff], True
