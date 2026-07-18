"""Dead-man's-switch: an OUTBOUND heartbeat to an external monitor.

secwatch's own checks (healthwatch.py) can tell you it's *degraded* — but a *dead*
secwatch (crashed process, hung box, pulled power) can't emit anything at all. The
fix is to invert it: ping an external monitor on an interval and let the monitor
alert on the ABSENCE of that ping. Point `monitoring.heartbeat_url` at an Uptime
Kuma "push" monitor, a healthchecks.io check, or any dead-man's-switch service.

Healthy cycles ping the up URL; a degraded self-check pings the fail URL (or the
up URL with status=down) so the monitor also catches *alive-but-broken*. The core
guarantee — "no ping ⇒ you get paged" — holds regardless of formatting, because
the monitor owns the alert. stdlib-only; a failed ping never raises into the loop.
"""
import asyncio
import logging
import urllib.parse
import urllib.request

from . import config, healthwatch

log = logging.getLogger("secwatch.heartbeat")


def _get(url, timeout=10):
    req = urllib.request.Request(url, headers={"User-Agent": "secwatch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return 200 <= r.status < 300


def _ping(base, status, msg):
    """Ping `base`, merging status+msg into the query (Kuma reads them; others
    harmlessly ignore them). Returns True on 2xx, False on any failure."""
    if not base:
        return False
    sep = "&" if "?" in base else "?"
    url = f"{base}{sep}status={status}&msg={urllib.parse.quote(msg[:100])}"
    try:
        return _get(url)
    except Exception as exc:  # a dead monitor must never take down the loop
        log.debug("heartbeat ping failed: %s", exc)
        return False


def send_once():
    """Emit one heartbeat reflecting the current health state. Returns bool sent."""
    st = healthwatch.STATE.get("status", "starting")
    if st in ("ok", "starting"):
        return _ping(config.HEARTBEAT_URL, "up", f"secwatch {st}")
    # degraded/alive-but-broken: prefer a dedicated fail URL, else signal down
    failing = [n for n, c in healthwatch.STATE.get("checks", {}).items()
               if not c.get("ok")]
    msg = "degraded: " + ",".join(failing) if failing else "degraded"
    return _ping(config.HEARTBEAT_FAIL_URL or config.HEARTBEAT_URL, "down", msg)


class Heartbeat:
    async def run(self):
        log.info("dead-man's-switch: heartbeat → %s every %ds",
                 config.HEARTBEAT_URL, config.HEARTBEAT_INTERVAL)
        while True:
            try:
                await asyncio.to_thread(send_once)
            except Exception:
                log.exception("heartbeat loop error")
            await asyncio.sleep(config.HEARTBEAT_INTERVAL)
