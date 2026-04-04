# DevMind — Automated PR Analysis

A GitHub Action that uses LLM to analyze pull requests and post automatic comments with risk assessment, evidence mapping, and security pattern detection.

## What it does

When a PR is opened or updated, DevMind:
- Analyzes the diff and identifies risk level (low/medium/high)
- Maps evidence to specific lines in the diff
- Detects security patterns (CVEs, token handling, TLS issues, broad exceptions)
- Posts a structured comment directly in the PR

## Example output
## Install in your repo (2 minutes)

1. Create `.github/workflows/devmind.yml`:
```yaml
name: DevMind PR Analysis
on:
  pull_request:
    types: [opened, synchronize, reopened]
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Analyze PR with DevMind
        id: devmind
        run: |
          RESPONSE=$(curl -s -X POST "${{ secrets.DEVMIND_API_URL }}/analyze-pr" \
            -H "Content-Type: application/json" \
            -H "X-Api-Key: ${{ secrets.DEVMIND_API_KEY }}" \
            -d "{\"repo\": \"${{ github.repository }}\", \"pr_number\": ${{ github.event.pull_request.number }}}")
          echo "response=$RESPONSE" >> $GITHUB_OUTPUT
      - name: Post comment
        uses: actions/github-script@v7
        with:
          script: |
            const raw = `${{ steps.devmind.outputs.response }}`;
            const data = JSON.parse(raw);
            const s = data.summary;
            const risk = s.risk || {};
            const riskEmoji = { low: '??', medium: '??', high: '??' }[risk.level] || '?';
            const body = `## ?? DevMind Analysis\n\n**${riskEmoji} Risk: ${(risk.level || 'unknown').toUpperCase()}** — ${risk.reason || ''}\n\n**What:** ${s.what || ''}\n**Why:** ${s.why || ''}\n\n**Review focus:** ${s.review_focus || ''}`;
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body
            });
```

2. Add these secrets in your repo settings (`Settings > Secrets > Actions`):

| Secret | Value |
|--------|-------|
| `DEVMIND_API_URL` | `https://devmind-2cej.onrender.com` |
| `DEVMIND_API_KEY` | `devmind-key-123` |

## Stack

- Backend: FastAPI + Groq (llama-3.3-70b)
- GitHub API for diff retrieval
- Deployed on Render

## Status

Alpha. Feedback welcome — open an issue or PR.
