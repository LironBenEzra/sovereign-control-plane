# syntax=docker/dockerfile:1

# ---- Stage 1: build the UI --------------------------------------------------
FROM node:24-alpine AS ui
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

# ---- Stage 2: the control plane, serving the API and the built UI -----------
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependencies first, against an empty package, so that editing source code does not
# reinstall Presidio and spaCy on every build.
COPY pyproject.toml ./
RUN mkdir -p src/control_plane \
    && touch src/control_plane/__init__.py \
    && pip install . \
    && pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_md-3.8.0/en_core_web_md-3.8.0-py3-none-any.whl

COPY src ./src
RUN pip install --no-deps --force-reinstall .

COPY policy ./policy
COPY scripts ./scripts
COPY --from=ui /ui/dist ./ui/dist

# Run unprivileged. /app/data holds the audit log, policy snapshots and keys.
RUN useradd --create-home --uid 10001 scp \
    && mkdir -p /app/data \
    && chown -R scp:scp /app/data
USER scp

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "control_plane.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
