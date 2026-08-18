#!/bin/sh
set -eu

# When executed without arguments, apply database migrations and launch the application server
if [ "$#" -eq 0 ]; then
    alembic upgrade head
    exec uvicorn faultwarden.main:app \
        --host "${FAULTWARDEN_HOST:-0.0.0.0}" \
        --port "${FAULTWARDEN_PORT:-8000}"
fi

# Pass through custom arguments (for CLI, test runners, or smoke tests)
exec "$@"
