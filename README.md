# DevMind — PR Analysis SaaS

AI-powered pull request analysis using Claude. Returns structured risk
assessment, technical summaries, and confidence scores for any GitHub PR.

---

## Project structure

```
devmind/
├── backend/
│   ├── main.py           ← FastAPI app: /analyze-pr, /webhook/github, /health
│   ├── summarizer.py     ← Claude API orchestration (single-pass + chunked)
│   ├── evaluator.py      ← Deterministic quality layer (risk, confidence, hallucinations)
│   ├── github.py         ← GitHub API: diffs, comments, metadata
│   ├── logger.py         ← JSONL append logger → logs/analyses.jsonl
│   ├── requirements.txt
│   ├── Dockerfile
│   ├── railway.toml
│   ├── render.yaml
│   ├── .env.example
│   └── tests/
│       └── run_eval.py   ← Eval suite: 8 real PRs, --debug mode
└── frontend/
    ├── src/
    │   ├── App.jsx       ← Full UI: input, risk display, summary, warnings
    │   ├── main.jsx
    │   └── index.css
    ├── index.html
    ├── package.json
    ├── vite.config.js
    ├── Dockerfile
    └── .env.example
```

---

## Local setup (Windows / Mac / Linux)

### 1. Backend

```bash
cd devmind/backend
python -m venv venv

# Windows
venv\Scripts\activate
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
# Edit .env — fill in GITHUB_TOKEN, ANTHROPIC_API_KEY, API_KEYS
uvicorn main:app --reload
# → http://localhost:8000
# → http://localhost:8000/docs  (Swagger UI)
```

### 2. Frontend

```bash
cd devmind/frontend
npm install
cp .env.example .env
# VITE_API_URL=http://localhost:8000
# VITE_API_KEY=dev-key-insecure  (must match API_KEYS in backend .env)
npm run dev
# → http://localhost:5173
```

### 3. API Keys

**GitHub Token**
1. github.com → Settings → Developer Settings → Personal Access Tokens → Fine-grained
2. Permissions: `Pull requests: Read` + `Contents: Read`
3. Set as `GITHUB_TOKEN` in `backend/.env`

**Anthropic API Key**
1. console.anthropic.com → API Keys → Create Key
2. Set as `ANTHROPIC_API_KEY` in `backend/.env`

**DevMind API Keys** (your own keys for protecting the API)
```bash
# Generate a strong key
python -c "import secrets; print(secrets.token_urlsafe(32))"
# Add to API_KEYS in backend/.env (comma-separated for multiple keys)
```

---

## API reference

All endpoints except `/health` require `X-Api-Key` header.

### `POST /analyze-pr`

```bash
curl -X POST http://localhost:8000/analyze-pr \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your-api-key" \
  -d '{"repo": "vercel/next.js", "pr_number": 12345}'
```

Response:
```json
{
  "pr_number": 12345,
  "repo": "vercel/next.js",
  "title": "...",
  "author": "...",
  "changed_files": 4,
  "additions": 87,
  "deletions": 23,
  "summary": {
    "what": "...",
    "why": "...",
    "impact": "...",
    "risk": { "level": "medium", "reason": "..." },
    "key_changes": ["..."],
    "review_focus": "...",
    "hallucination_warning": []
  },
  "evaluation": {
    "confidence": "high",
    "confidence_score": 0.71,
    "specificity_score": 0.82,
    "is_flagged": false,
    "flag_reason": null,
    "generic_phrases_found": []
  },
  "pre_analysis": {
    "risk_floor": "medium",
    "risk_tags": ["api"],
    "flagged_files": ["src/server/router.ts"],
    "trivially_touched": [],
    "files_with_diff": 4,
    "total_diff_chars": 3241
  }
}
```

### `GET /health`

No auth required. Returns `{"status": "ok"}`. Used by Railway/Render for health checks.

### `GET /logs?n=50`

Returns last n analysis log entries from `logs/analyses.jsonl`.

### `POST /webhook/github`

Receives GitHub `pull_request` events (opened, synchronize, reopened).
Triggers analysis in background. Returns 202 immediately.

---

## Deployment

### Option A — Railway (recommended, easiest)

1. Push repo to GitHub
2. railway.app → New Project → Deploy from GitHub repo
3. Select the `backend/` directory
4. Add environment variables in Railway dashboard:
   - `GITHUB_TOKEN`
   - `ANTHROPIC_API_KEY`
   - `API_KEYS`
   - `GITHUB_WEBHOOK_SECRET`
   - `FRONTEND_ORIGIN` (your frontend URL once deployed)
5. Railway auto-detects `railway.toml` and deploys

For the frontend, create a second Railway service pointing at `frontend/`:
- Add build args: `VITE_API_URL=https://your-backend.railway.app`
- Add build arg: `VITE_API_KEY=your-api-key`

### Option B — Render

1. render.com → New → Web Service → Connect GitHub repo
2. Root directory: `backend`
3. Render auto-detects `render.yaml`
4. Add environment variables in Render dashboard (same as above)

For the frontend: New → Static Site → Root `frontend/`
- Build command: `npm install && npm run build`
- Publish directory: `dist`
- Add env vars: `VITE_API_URL`, `VITE_API_KEY`

### Option C — Docker Compose (self-hosted)

```yaml
# docker-compose.yml (create at project root)
version: "3.9"
services:
  api:
    build: ./backend
    ports: ["8000:8000"]
    env_file: ./backend/.env
    volumes:
      - ./backend/logs:/app/logs

  web:
    build:
      context: ./frontend
      args:
        VITE_API_URL: http://localhost:8000
        VITE_API_KEY: your-api-key
    ports: ["80:80"]
    depends_on: [api]
```

```bash
docker-compose up --build
```

---

## GitHub Webhook setup

After deploying the backend:

1. Go to your GitHub repo → Settings → Webhooks → Add webhook
2. Payload URL: `https://your-backend-domain.com/webhook/github`
3. Content type: `application/json`
4. Secret: generate with `python -c "import secrets; print(secrets.token_hex(32))"`
   — set the same value as `GITHUB_WEBHOOK_SECRET` in your backend env
5. Events: select **Pull requests** only
6. Save

Every time a PR is opened, updated, or reopened, DevMind will automatically
analyse it and log the result to `logs/analyses.jsonl`.

---

## Rate limits

Default: 20 requests / 60 seconds per API key.
Adjust with env vars: `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW_S`.

> In-memory only. If you run multiple workers or containers, switch to Redis.

---

## Eval suite

```bash
cd backend

# Full suite — 8 real PRs (~2-3 min)
python tests/run_eval.py

# Debug mode — raw Claude output + parsed JSON + pre_analysis
python tests/run_eval.py --debug

# Single category
python tests/run_eval.py tiny
python tests/run_eval.py --debug high-risk

# Risk dampening verification
python tests/run_eval.py --dampening
```

---

## Environment variables reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_TOKEN` | ✓ | — | GitHub Personal Access Token |
| `ANTHROPIC_API_KEY` | ✓ | — | Anthropic API key |
| `API_KEYS` | ✓ | `dev-key-insecure` | Comma-separated list of valid API keys |
| `GITHUB_WEBHOOK_SECRET` | — | — | HMAC secret for webhook signature verification |
| `FRONTEND_ORIGIN` | — | `http://localhost:5173` | CORS allowed origin |
| `RATE_LIMIT_REQUESTS` | — | `20` | Max requests per window per API key |
| `RATE_LIMIT_WINDOW_S` | — | `60` | Rate limit window in seconds |
| `ANALYSIS_TIMEOUT_S` | — | `120` | Hard timeout for one PR analysis |

---

## Roadmap

- [x] PR Summarizer with Claude
- [x] Risk heuristics (auth, db, infra, concurrency...)
- [x] Confidence + usefulness scoring
- [x] Hallucination detection
- [x] API key auth + rate limiting
- [x] GitHub webhook (auto-trigger on PR open/sync)
- [x] Structured JSON logging
- [x] Docker + Railway/Render deploy
- [ ] Explain this repo
- [ ] Auto changelog
- [ ] GitHub OAuth (user login)
- [ ] Usage dashboard
- [ ] Stripe billing
