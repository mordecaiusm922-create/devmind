# ── Stage 1: Builder ───────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Install dependencies into a venv so we can copy them cleanly
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ───────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

WORKDIR /app

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code — only what's needed at runtime
COPY main.py        .
COPY summarizer.py  .
COPY evaluator.py   .
COPY github.py      .
COPY logger.py      .

# Create logs directory (volume can be mounted over this)
RUN mkdir -p /app/logs

# Non-root user for security
RUN adduser --disabled-password --gecos "" appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Use 1 worker in Railway/Render free tier (single container).
# Scale workers with WEB_CONCURRENCY env var on paid tiers.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--access-log"]
