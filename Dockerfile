# syntax=docker/dockerfile:1

# --- Builder Stage ---
FROM python:3.14-slim AS builder

ENV UV_PYTHON_DOWNLOADS=0 \
    UV_LINK_MODE=copy

WORKDIR /app

# Copy uv binary from the official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Cache dependencies layer using uv.lock
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync \
        --locked \
        --no-install-project \
        --no-editable

# Copy source and build immutable application distribution
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync \
        --locked \
        --no-editable


# --- Runtime Stage ---
FROM python:3.14-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    FAULTWARDEN_HOST=0.0.0.0 \
    FAULTWARDEN_PORT=8000

# Create non-root system user and group
RUN groupadd --system --gid 10001 faultwarden \
    && useradd \
        --system \
        --uid 10001 \
        --gid faultwarden \
        --no-create-home \
        faultwarden

WORKDIR /app

# Copy virtualenv and required runtime assets
COPY --from=builder --chown=faultwarden:faultwarden /app/.venv /app/.venv
COPY --chown=faultwarden:faultwarden migrations ./migrations
COPY --chown=faultwarden:faultwarden alembic.ini ./alembic.ini
COPY --chown=faultwarden:faultwarden docker-entrypoint.sh ./docker-entrypoint.sh

RUN chmod 0555 /app/docker-entrypoint.sh

USER 10001:10001

EXPOSE 8000

ENTRYPOINT ["/app/docker-entrypoint.sh"]
