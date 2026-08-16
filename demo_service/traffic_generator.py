"""Lightweight development-only traffic generator for demo-service."""

import os
import sys
import time
import urllib.error
import urllib.request

# Target URL for traffic generation
TARGET_URL = os.getenv("TRAFFIC_TARGET_URL", "http://demo-service:8001/")
INTERVAL_SECONDS = float(os.getenv("TRAFFIC_INTERVAL_SECONDS", "1.0"))


def generate_traffic() -> None:
    """Continuously issue HTTP requests to the target service to produce telemetry."""
    print(
        f"[traffic-generator] Starting continuous requests to {TARGET_URL} (interval: {INTERVAL_SECONDS}s)",
        flush=True,
    )

    while True:
        try:
            req = urllib.request.Request(
                TARGET_URL,
                headers={"User-Agent": "FaultWarden-TrafficGenerator/1.0"},
            )
            # Short timeout so generator never hangs indefinitely
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
                print(f"[traffic-generator] Request OK -> HTTP {status}", flush=True)
        except urllib.error.HTTPError as exc:
            # Expected when error mode is active (e.g. HTTP 500)
            print(f"[traffic-generator] Request returned error -> HTTP {exc.code}", flush=True)
        except Exception as exc:
            # Network glitches, service starting up, etc.
            print(f"[traffic-generator] Connection issue: {exc}", flush=True)

        time.sleep(INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        generate_traffic()
    except KeyboardInterrupt:
        print("[traffic-generator] Stopped by operator.", flush=True)
        sys.exit(0)
