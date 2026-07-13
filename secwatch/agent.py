"""secwatch host agent — runs ONLY the host-level collectors (auth log, host
baseline/persistence, process/egress, docker/systemd) and forwards their events
to a secwatch core over HTTP. Lets the core run as an isolated container while
the agent (which needs deep host access) runs on the host.

Run with:  SECWATCH_MODE=agent SECWATCH_CORE_URL=http://core:8931 \
           SECWATCH_INGEST_TOKEN=... python -m secwatch.agent
"""
import asyncio
import json
import logging
import urllib.request

from . import (auditwatch, authwatch, config, db, detect, dockerwatch,
               hostwatch, procwatch)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
log = logging.getLogger("secwatch.agent")

_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)


def _forward(event):
    try:
        _queue.put_nowait(event)
    except asyncio.QueueFull:
        log.warning("forward queue full; dropping %s", event.get("rule"))


def _post(event):
    req = urllib.request.Request(
        config.CORE_URL.rstrip("/") + "/api/ingest",
        data=json.dumps(event).encode(),
        headers={"Content-Type": "application/json",
                 "X-Secwatch-Token": config.INGEST_TOKEN})
    with urllib.request.urlopen(req, timeout=10) as r:
        return 200 <= r.status < 300


async def _shipper():
    while True:
        event = await _queue.get()
        try:
            await asyncio.to_thread(_post, event)
        except Exception as exc:
            log.error("ship failed (%s): %s", event.get("rule"), exc)


async def main():
    if not config.INGEST_TOKEN:
        log.error("SECWATCH_INGEST_TOKEN is required in agent mode")
        return
    log.info("secwatch agent → core %s", config.CORE_URL)
    conn = db.connect()   # local DB holds only baseline state; events are forwarded
    engine = detect.Engine(conn, alert_cb=None, forward_cb=_forward)
    tasks = [
        asyncio.create_task(_shipper()),
        asyncio.create_task(authwatch.AuthWatcher(engine, conn).run()),
        asyncio.create_task(hostwatch.HostWatcher(engine, conn).run()),
        asyncio.create_task(procwatch.ProcWatcher(engine, conn).run()),
        asyncio.create_task(auditwatch.AuditWatcher(engine, conn).run()),
        asyncio.create_task(dockerwatch.DockerWatcher(engine, conn).run()),
    ]
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
