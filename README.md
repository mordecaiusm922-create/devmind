# DevMind - PR Risk Engine

Detects security vulnerabilities in pull requests before they reach production.

## What it does

Every PR gets:
- Risk level: LOW / MEDIUM / HIGH / CRITICAL
- Risk Score: 0-100 numeric score with breakdown
- Vulnerability detection: credential exposure, SQL injection, CVEs, auth bypass
- Evidence: exact file names and line numbers
- Fix recommendations: concrete steps to remediate

## Benchmark

100% accuracy on 10 real GitHub PRs.

| PR | Expected | Got |
|---|---|---|
| psf/requests#6710 (CVE-2024-35195) | medium | medium |
| django/django#17473 (hardcoded SECRET_KEY) | critical | critical |
| pallets/flask#5992 (13 CVEs) | high | high |
| psf/black#3864 (mypy bump) | low | low |

## Status

Alpha. Feedback welcome - open an issue or reach out.
