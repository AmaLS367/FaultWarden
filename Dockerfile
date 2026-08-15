FROM python:3.14-slim AS builder

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv pip install --system --no-cache .

FROM python:3.14-slim AS runtime

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY src /app/src
COPY migrations /app/migrations
COPY alembic.ini /app/alembic.ini

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1 \
    FAULTWARDEN_HOST=0.0.0.0 \
    FAULTWARDEN_PORT=8000

EXPOSE 8000

CMD ["uvicorn", "faultwarden.main:app", "--host", "0.0.0.0", "--port", "8000"]
