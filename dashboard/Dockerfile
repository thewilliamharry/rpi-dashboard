FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    UV_CACHE_DIR=/tmp/uv-cache \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app

RUN python -m pip install --no-cache-dir uv==0.11.28
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project && \
    playwright install --with-deps chromium && \
    rm -rf /tmp/uv-cache /var/lib/apt/lists/*

RUN groupadd --gid 10001 beacon && \
    useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin beacon && \
    mkdir -p /data /tmp && chown -R beacon:beacon /data /app

COPY --chown=beacon:beacon app.py worker.py runtime_smoke.py index.html app.js style.css ./

USER 10001:10001
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "1", "--threads", "8", "--timeout", "60", "--access-logfile", "-", "app:app"]
