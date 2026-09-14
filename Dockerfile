# Multi-stage: dependencies resolve in a layer that only changes when the lock
# changes, and the runtime image carries no build tooling and no root shell.
FROM ghcr.io/astral-sh/uv:0.12.3 AS uv

FROM python:3.12-slim AS builder
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

# Dependencies first, without the project, so source edits do not bust the layer.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
# git is a runtime dependency: F2 asks git whether a .env is tracked, and the
# answer is the difference between a confirmed finding and an inferred one.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 preflight

COPY --from=builder --chown=preflight:preflight /app /app
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER preflight
WORKDIR /app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"

# PREFLIGHT_ALLOWED_ROOTS must be set for the service to accept any scan at all.
CMD ["uvicorn", "preflight.service.app:app", "--host", "0.0.0.0", "--port", "8000"]
