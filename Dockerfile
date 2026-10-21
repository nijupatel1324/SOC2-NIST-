# =============================================================================
# Cybersecurity GRC & Compliance Management Platform — Dockerfile
# =============================================================================
# Multi-stage build:
#   Stage 1 (builder) — install Python deps into a virtual env
#   Stage 2 (runtime) — minimal image, non-root user, no build toolchain
# =============================================================================

# --------------------------------------------------------------------------- #
# Stage 1: Dependency Builder                                                  #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

# Security: no interactive prompts, deterministic locale
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install OS-level build deps for native wheels (e.g., cryptography, psycopg2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install into a dedicated virtual env
COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt

# --------------------------------------------------------------------------- #
# Stage 2: Runtime Image                                                       #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

# Security: minimal environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    ENVIRONMENT=production \
    DEBUG=False

# Install runtime-only OS deps (libpq for PostgreSQL driver)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user/group for least-privilege execution
RUN groupadd --system grc && \
    useradd --system --gid grc --no-create-home --shell /usr/sbin/nologin grc

# Bring in virtual env from builder stage
COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

# Copy application source
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY pyproject.toml .

# Create directories the app needs and assign ownership
RUN mkdir -p /app/uploads /app/logs && \
    chown -R grc:grc /app

# Drop to non-root user
USER grc

# Expose application port (behind reverse-proxy: nginx / Traefik)
EXPOSE 8000

# Liveness probe used by Docker / Kubernetes
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

# Default entrypoint: production Uvicorn
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--no-access-log", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
