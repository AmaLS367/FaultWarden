"""Standalone worker process entrypoint for FaultWarden durable investigation jobs."""

import asyncio
import contextlib
import signal
import sys

from faultwarden.core.config import get_settings
from faultwarden.core.logging import get_logger, setup_logging
from faultwarden.services.job_worker import JobWorker

logger = get_logger("faultwarden.worker")


async def main() -> None:
    """Initialize and run the durable job worker process."""
    settings = get_settings()
    setup_logging(log_level=settings.server.log_level, environment=settings.server.env)

    logger.info("starting_faultwarden_worker", env=settings.server.env)

    worker = JobWorker(settings=settings)

    # Set up graceful shutdown handlers
    loop = asyncio.get_running_loop()

    def _shutdown() -> None:
        logger.info("shutdown_signal_received")
        worker.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, _shutdown)

    try:
        await worker.run_loop()
    except KeyboardInterrupt:
        logger.info("worker_stopped_via_keyboard_interrupt")
    finally:
        logger.info("faultwarden_worker_exited")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
