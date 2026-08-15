# Contributing to FaultWarden

## Development Setup

```bash
uv sync --all-extras --dev
cp .env.example .env
```

## Before Submitting a Change

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -v --cov=src
```

See [AGENTS.md](AGENTS.md) for the full set of architectural invariants, repository
layout, and coding conventions that apply to all contributions.

---

## Comment Conventions

FaultWarden uses four distinct comment forms. Never mix them — each form signals something
different to the reader. See `src/faultwarden/main.py` for a reference implementation.

1. **Function docstrings** — a one-line summary in triple quotes directly under the
   `def`/`async def` line:
   ```python
   def create_engine(settings: DatabaseSettings) -> AsyncEngine:
       """SQLite URLs should produce an engine without pool sizing kwargs."""
   ```
   For non-trivial functions, extend the docstring with further explanatory sentences
   after the summary line.

2. **Zone markers** — three dashes on each side, marking a major logical section of a
   file (e.g. a group of related routes, middleware, or handlers):
   ```python
   # --- Exception Handlers ---
   ```

3. **Sub-zone markers** — a single leading dash, marking a subsection inside a zone. A
   sub-zone marker is only valid nested under a preceding `# --- ... ---` zone marker; it
   must never appear on its own without an enclosing zone. If a group of related lines
   deserves a label but has no enclosing zone, give it its own zone marker instead of a
   bare sub-zone marker:
   ```python
   # --- Routers ---
   # Direct top-level health & metrics endpoints
   app.include_router(health_router)
   ...

   # - API v1 routes
   app.include_router(api_router, prefix="/api/v1")
   ```

4. **Plain comments** — a short, single-line explanation of a specific line or block,
   with no dash decoration, used when neither a docstring nor a zone marker applies:
   ```python
   # Initialize tables automatically when running with SQLite (e.g. dev/tests)
   ```

### When to Add a Comment

* **A function contains two or more zones** — delimit each with a zone marker so the
  boundaries are visible at a glance (`main.py`'s `create_app()` is the reference: CORS,
  Middleware, Exception Handlers, Routers).
* **A decision is non-typical** — a workaround, a deliberate deviation from the "obvious"
  approach, a spec quirk (e.g. disabling CORS credentials on a wildcard origin): explain
  *why* right there. The next reader can't reconstruct that reasoning from the code alone.
* **A hidden constraint or invariant governs correctness** — must run before X, must stay
  sorted, can't exceed Y: call it out, since nothing in the code's shape signals it.
* **A workaround exists for something outside this codebase** — a library bug, a platform
  limitation, a third-party API quirk: note what is being worked around, so it doesn't get
  "cleaned up" later and the bug comes back.
* **Comments explain *why*, never *what*** — if a comment only restates what the code
  already says, delete it; a well-named function or variable already covers that.
* **Don't comment the obvious** — no comment beats one that just echoes the line below it.
