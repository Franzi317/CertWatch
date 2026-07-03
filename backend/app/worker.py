"""Queue-driven worker process (Task 8).

`process_one` claims a single item from the Task 7 work queue and executes
it; `run_forever` polls in a loop and is the entry point for both the
embedded worker thread (see `main.py` lifespan, `CERTWATCH_EMBEDDED_WORKER`)
and the standalone `python -m app.worker` process used in production
(`docker-compose.yml`'s `worker` service).
"""
from __future__ import annotations

import logging
import time

from . import queue, scan_engine
from .db import SessionLocal

log = logging.getLogger("certwatch.worker")


def process_one(db) -> bool:
    """Claim and execute one queue item. Returns True if an item was
    processed (regardless of success/failure), False if the queue was empty."""
    item = queue.claim(db)
    if item is None:
        return False

    if item.kind == "scan":
        try:
            scan_engine.run_scan_job(item.payload["scan_job_id"])
        except Exception as e:  # noqa: BLE001 - any scan failure must not kill the worker
            log.exception("scan job failed (queue item %s)", item.id)
            queue.fail(db, item, str(e))
        else:
            queue.complete(db, item)
    else:
        queue.fail(db, item, f"unknown kind: {item.kind}")

    return True


def run_forever(poll_interval: float = 2.0, stop_event=None) -> None:
    """Poll the queue until the process is killed (or `stop_event` is set,
    for the embedded in-process worker thread). An exception in one
    iteration is logged and never kills the loop."""
    log.info("worker started (poll_interval=%s)", poll_interval)
    while stop_event is None or not stop_event.is_set():
        try:
            db = SessionLocal()
            try:
                processed = process_one(db)
            finally:
                db.close()
        except Exception:  # noqa: BLE001 - keep polling no matter what
            log.exception("worker iteration failed")
            processed = False
        if not processed:
            if stop_event is not None:
                stop_event.wait(poll_interval)
            else:
                time.sleep(poll_interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    run_forever()


if __name__ == "__main__":
    main()
