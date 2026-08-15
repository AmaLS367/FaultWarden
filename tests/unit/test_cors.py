"""Unit tests for CORS configuration wiring."""

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import faultwarden.main as main_module
from faultwarden.core.config import Settings


def _cors_middleware_kwargs(app: FastAPI) -> dict[str, Any]:
    entry = next(m for m in app.user_middleware if m.cls is CORSMiddleware)
    return dict(entry.kwargs)


def test_wildcard_cors_origin_disables_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """A wildcard origin config must not enable credentials (browsers reject the combo)."""
    settings = Settings(cors_origins="*")
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)

    app = main_module.create_app()
    kwargs = _cors_middleware_kwargs(app)

    assert kwargs["allow_origins"] == ["*"]
    assert kwargs["allow_credentials"] is False


def test_explicit_cors_origins_enable_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Explicit origins should be passed through as-is with credentials enabled."""
    settings = Settings(cors_origins="http://localhost:3000,https://app.example.com")
    monkeypatch.setattr(main_module, "get_settings", lambda: settings)

    app = main_module.create_app()
    kwargs = _cors_middleware_kwargs(app)

    assert kwargs["allow_origins"] == ["http://localhost:3000", "https://app.example.com"]
    assert kwargs["allow_credentials"] is True
