"""Unit tests for structured logging configuration."""

import logging

from faultwarden.core.logging import get_logger, setup_logging


def test_setup_logging_development_uses_console_renderer() -> None:
    """Development environment should configure a colorized console handler."""
    setup_logging(log_level="DEBUG", environment="development")

    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0], logging.StreamHandler)

    logger = get_logger("faultwarden.test")
    logger.info("test_log_event", key="value")


def test_setup_logging_production_uses_json_renderer() -> None:
    """Production/staging environments should configure JSON logging."""
    setup_logging(log_level="WARNING", environment="production")

    root_logger = logging.getLogger()
    assert root_logger.level == logging.WARNING
    assert len(root_logger.handlers) == 1

    logger = get_logger("faultwarden.test")
    logger.warning("test_log_event_prod", key="value")


def test_setup_logging_falls_back_to_info_for_unknown_level() -> None:
    """An unrecognized log level string should default to INFO."""
    setup_logging(log_level="NOT_A_LEVEL", environment="development")

    assert logging.getLogger().level == logging.INFO
