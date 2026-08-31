# devmind-mcp -- containerized build.
#
# Mirrors Render's existing native-Python deploy exactly (same Python
# version, same build command, same start command) so this image is a
# drop-in alternative deploy path, not a behavior change. See
# devmind_server.py for the actual application; PORT is read from the
# environment at startup, same as today, so no port is hardcoded here.

FROM python:3.11-slim

WORKDIR /app

# System deps: none needed beyond what python:3.11-slim already has --
# the app's dependencies (fastapi, mcp, supabase, e2b, etc.) are all
# pure-Python or ship their own wheels.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user, same hardening pattern as backend/Dockerfile (the
# earlier pre-MCP-pivot service) -- least privilege inside the
# container even though E2B already isolates command execution itself.
RUN adduser --disabled-password --gecos "" devmind && \
    chown -R devmind:devmind /app
USER devmind

# Render (and most PaaS Docker runners) inject PORT at runtime; the
# app already reads it via os.getenv("PORT", "8000") -- EXPOSE here is
# documentation only, it doesn't bind anything.
EXPOSE 8000

CMD ["python", "devmind_server.py"]